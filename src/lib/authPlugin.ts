import { Elysia, t, Static } from "elysia"
import { Value } from '@sinclair/typebox/value'
import { TAnySchema } from "@sinclair/typebox"
import { verify, sign, decode } from "jsonwebtoken"

const ProviderResponseSchema = t.Object({
  id_token: t.String()
})

const IdTokenPayloadSchema = t.Object({
  sub: t.String(),
  name: t.Optional(t.String()),
  email: t.Optional(t.String()),
})
export type IdTokenPayload = Static<typeof IdTokenPayloadSchema>

type Provider = {
  tokenEndpoint: string
  clientId: string
  clientSecret: string
  redirectUri: string
}

type PluginConfigParams = {
  providers: Record<string, Provider>
  jwt: {
    secret: string
    expiration: string
  }
  session: {
    authHeader: string
    tokenPrefix: string
  }
}

export class AuthenticationError extends Error {
  constructor() {
    super()
  }
}

export class AuthorizationError extends Error {
  constructor() {
    super()
  }
}

const asyncVerify = (token: string, secret: string) =>
  new Promise((resolve, reject) => verify(token, secret, (error, payload) => {
    if (error) reject(error)
    else resolve(payload)
  }))

const asyncSign = (payload: object, secret: string, config: { expiresIn: string }) =>
  new Promise((resolve: (token: string) => void, reject) =>
    sign(payload, secret, config, (error, token) => {
      if (error)
        return reject(error)
      if (!token)
        return reject(null)
      resolve(token)
    }))

const logger = (forwardLogs: (message:string) => void) => {
  const logLevel = (process.env.AUTH_LOG_LEVEL || process.env.LOG_LEVEL || "off").toLowerCase()
  const logLevels = [ "fatal", "error", "warn", "info", "debug", "trace", "all" ]
  const log = (reqMinLogLevel: string, message: string) => {
    const shouldLog = logLevels.indexOf(logLevel) >= logLevels.indexOf(reqMinLogLevel)
    if (shouldLog)
      forwardLogs(message)
  }
  return log
}

const safeStringify = (data: unknown) => {
  try {
    return JSON.stringify(data)
  } catch (err) {
    return "" + data
  }
}

export const multiProviderAuth = <const SessionUser extends TAnySchema>(
  sessionUser: SessionUser,
  login: (idTokenPayload: IdTokenPayload, provider: string) =>
    Promise<Static<typeof sessionUser> | null>,
  config: PluginConfigParams,
  forwardLogs: (logMessage: string) => void = (err) => console.log(err)
) => {
  const log = logger(forwardLogs)
  log('info' ,`Auth plugin added`)

  type AuthResponse = Promise<IdTokenPayload | null>
  const authWithProvider = async (code: string, provider: Provider): AuthResponse => {
    try {
      const response = await fetch(provider.tokenEndpoint, {
        method: "POST",
        body: JSON.stringify({
          code,
          client_id: provider.clientId,
          client_secret: provider.clientSecret,
          redirect_uri: provider.redirectUri,
          scope: 'openid email profile',
          grant_type: 'authorization_code',
        })
      })
      const data = await response.json()
      const responsePayload = Value.Decode(ProviderResponseSchema, data)
      const idTokenPayload = decode(responsePayload.id_token) as unknown
      const userData = Value.Decode(IdTokenPayloadSchema, idTokenPayload)
      return userData
    } catch (error) {
      log("error", "" + error)
      return null
    }
  }

  const plugin = new Elysia({ name: "X-auth-middleware" })
    .error({
      AuthenticationError,
      AuthorizationError,
    })
    .onError(({ code, set }) => {
      if (code === "AuthenticationError") {
          log("trace", "HTTP 401")
          set.status = 401
          return
      }
      if (code === "AuthorizationError") {
        log("trace", "HTTP 403")
        set.status = 403
        return
      }
    })
    .derive(async (ctx) => {
      const authHeader = ctx.headers[config.session.authHeader]
      if (!authHeader)
        return { ...ctx, user: null }
      try {
        const token = authHeader.split(config.session.tokenPrefix)[1]
        const jwtPayload = await asyncVerify(token, config.jwt.secret)
        const user = Value.Decode(sessionUser, jwtPayload)
        log("info", `[${ctx.request.method}] ${ctx.path} - ${JSON.stringify(user)}`)
        return { ...ctx, user }
      } catch (error) {
        log("error", safeStringify(error))
        return { ...ctx, user: null }
      }
    })
    .post("/social-login", async ({ body }) => {
      const providerName = body.provider || "default"
      const provider = config.providers[providerName]
      if (!provider)
        throw new AuthenticationError()

      log("info", `[POST] - /social-login`)
      const idTokenPayload = await authWithProvider(body.code, provider)
      if (!idTokenPayload)
        throw new AuthenticationError()

      const sessionData = await login(idTokenPayload, providerName)
      if (!sessionData)
        throw new AuthorizationError()

      const token = await asyncSign(sessionData, config.jwt.secret, {
        expiresIn: config.jwt.expiration
      })

      return { sessionToken: `${config.session.tokenPrefix}${token}` }
    }, {
      body: t.Object({
        code: t.String(),
        provider: t.Optional(t.String()),
      }),
      response: t.Object({
        sessionToken: t.String()
      })
    })

  return plugin
}

export const auth = <const SessionUser extends TAnySchema>(
  sessionUser: SessionUser,
  login: (idTokenPayload: IdTokenPayload) =>
    Promise<Static<typeof sessionUser> | null>,
  forwardLogs: (logMessage: string) => void = (error) => console.log(error)
) => {
  const log = logger(forwardLogs)

  const EnvSchema = t.Object({
    jwtSecret: t.String(),
    jwtExp: t.String(),
    tokenEndpoint: t.String(),
    clientId: t.String(),
    clientSecret: t.String(),
    redirectUri: t.String(),
  })

  const envVars = {
    jwtSecret: process.env.JWT_SECRET,
    jwtExp: process.env.JWT_EXP,
    tokenEndpoint: process.env.TOKEN_ENDPOINT,
    clientId: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    redirectUri: process.env.REDIRECT_URI,
  }

  const errors = [ ...Value.Errors(EnvSchema, envVars) ]
  if (errors.length) {
    log("info", JSON.stringify(errors, null, 2))
    process.exit(1)
  }

  const env = Value.Decode(EnvSchema, envVars)  

  return multiProviderAuth(
    sessionUser,
    login,
    {
      jwt: {
        secret: env.jwtSecret,
        expiration: env.jwtSecret,
      },
      session: {
        authHeader: "authorization",
        tokenPrefix: "Bearer "
      },
      providers: {
        "default": {
          tokenEndpoint: env.tokenEndpoint,
          clientId: env.clientId,
          clientSecret: env.clientSecret,
          redirectUri: env.redirectUri,
        }
      }
    },
    forwardLogs,
  )
}
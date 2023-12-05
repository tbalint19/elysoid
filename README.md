# Elysoid

Minimal, fully typesafe OpenID Elysia plugin for single page apps with
stateless session management with JWT.

### Basic setup

```bash
bun add elysoid
```

```ts
// plugin/auth.ts
import { Static, t } from "elysia"
import { IdTokenPayload, auth as authPlugin } from "elysoid"

const SessionSchema = t.Object({
  id: t.String(),
  roles: t.Array(t.String())
}) // create any session schema that you need for your app
type Session = Static<typeof SessionSchema>

// type IdTokenPayload = { sub: string, email?: string, name?: string }
const login = async (payload: IdTokenPayload): Promise<Session | null> => {
  
  // Get user from DB, based on "sub" (or create)
  // - with all required data for session
  // - return null if not authorized to login

  return {
    id: "1",
    roles: [ "admin" ]
  }
}

export const auth = authPlugin(SessionSchema, login)
```

```ts
// index.ts
import { Elysia, t } from "elysia"
import { AuthenticationError, AuthorizationError } from "elysoid"
import { auth } from "./plugin/auth"

const app = new Elysia()
  .use(auth)  // /social-login endpoint registered - see eden treaty below
  .post("/api/demo", ({ body, user }) => { // user is typed as Session | null
    if (!user)
      throw new AuthenticationError()       // handled, will return 401
    if (!user.roles.includes("admin"))
      throw new AuthorizationError()        // handled, will return 403
    return { msg: `${body.data} received from ${user.id}` }
  },
  {
    body: t.Object({ data: t.String() }),
    response: t.Object({ msg: t.String() })
  })
  .listen(3000)

console.log(
  `🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`
)

export type App = typeof app
```

```bash
# .env (or environment variables)
TOKEN_ENDPOINT=https://openidprovider.com/token
CLIENT_ID=yourlientid
CLIENT_SECRET=yourclientsecret
REDIRECT_URI=https://yourapp.com/callback

JWT_SECRET=shhhh
JWT_EXP=2h

LOG_LEVEL=trace
# and / or
AUTH_LOG_LEVEL=trace    # takes precedence
# default log level is off - no logs from auth plugin
# [ "fatal", "error", "warn", "info", "debug", "trace", "all" ]
```

```ts
// on the client
import { edenTreaty } from '@elysiajs/eden'
import type { App } from '../../api/src/index'

const app = edenTreaty<App>('http://localhost:3000')

const login = async () => {
  // get code from url (query param)
  const response = await app['social-login'].post({
    code: "<from query param>"
  })
  // type Response = { sessionToken: string }
  // save sessionToken
  // and then send it on all subsequent request
  // in "authorization" header
}
```

And that's it.

### Advanced setup

You might want to connect to multiple providers, or configure certain other
aspects of the plugin. With the typed config it is pretty self-explanatory, here
is a full example nonetheless.

```ts
// plugin/auth.ts
import { Static, t } from "elysia"
import { IdTokenPayload, multiProviderAuth as authPlugin } from "elysoid"

const SessionSchema = t.Object({
  id: t.String(),
  roles: t.Array(t.String())
}) // create any session schema that you need for your app
type Session = Static<typeof SessionSchema>

// type IdTokenPayload = { sub: string, email?: string, name?: string }
const login = async (payload: IdTokenPayload, provider: string): Promise<Session | null> => {
  
  // Get user from DB, based on "sub" (or create)
  // - BASED ON PROVIDER!!! ("google", "apple"... see below in the config)
  // - with all required data for session
  // - return null if not authorized to login

  return {
    id: "1",
    roles: [ "admin" ]
  }
}

export const auth = authPlugin(SessionSchema, login, {
  session: {
    authHeader: "authorization",
    tokenPrefix: "Bearer ",
  },
  jwt: {
    secret: "shhh",
    expiration: "2h",
  },
  providers: {
    'google': {
      tokenEndpoint: "https://google.com/token",
      clientId: "yourgoogleclientid",
      clientSecret: "yourgoogleclientsecret",
      redirectUri: "https://yourapp.com/googlecb"
    },
    'apple': {
      tokenEndpoint: "https://apple.com/token",
      clientId: "yourappleclientid",
      clientSecret: "yourappleclientsecret",
      redirectUri: "https://yourapp.com/applecb"
    },
  }
}, (logMessage) => console.log(logMessage)) 
```

```ts
// on the client
import { edenTreaty } from '@elysiajs/eden'
import type { App } from '../../api/src/index'

const app = edenTreaty<App>('http://localhost:3000')

const login = async () => {
  // get code from url (query param)
  const response = await app['social-login'].post({
    code: "<from query param>",
    provider: "google"  // based on where were you redirected to
  })
  // type Response = { sessionToken: string }
  // save sessionToken
  // and then send it on all subsequent request
  // in "authorization" header
}
```


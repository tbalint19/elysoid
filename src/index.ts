import { Elysia, t } from "elysia"
import { AuthenticationError, AuthorizationError } from "./lib/authPlugin"
import { authPlugin } from "./plugin/auth"

const app = new Elysia()
  .use(authPlugin)
  .post("/api/demo", ({ body, user }) => {
    if (!user)
      throw new AuthenticationError()
    if (user.id !== "a")
      throw new AuthorizationError()
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

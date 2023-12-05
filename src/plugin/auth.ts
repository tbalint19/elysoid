import { Static, t } from "elysia"
import { IdTokenPayload, auth, multiProviderAuth } from "../lib/authPlugin"

const SessionSchema = t.Object({
  id: t.String(),
})

type Session = Static<typeof SessionSchema>

const login = async (payload: IdTokenPayload): Promise<Session | null> => {
  
  // Todo
  // Get user from DB (or create)
  // - with all required data for session
  // - return null if not authorized to login

  return {
    id: payload.sub,
  }
}

export const authPlugin = auth(SessionSchema, login)
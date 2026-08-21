import React, { createContext, useContext } from "react";
import { User } from "./api";

const UserContext = createContext<User | null>(null);

export function UserProvider({ user, children }: { user: User; children: React.ReactNode }) {
  return <UserContext.Provider value={user}>{children}</UserContext.Provider>;
}

/** Current authenticated user, for components below <Layout> that aren't
 * reachable via prop-drilling (the gallery hub tree in particular). Existing
 * workflow components keep receiving `role` as an explicit prop — this is
 * additive, not a forced migration. */
export function useUser(): User {
  const user = useContext(UserContext);
  if (!user) throw new Error("useUser() called outside <UserProvider>");
  return user;
}

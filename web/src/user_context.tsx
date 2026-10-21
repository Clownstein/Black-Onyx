import React, { createContext, useContext } from "react";
import { User } from "./api";

type UserContextValue = {
  user: User;
  setUser: (user: User) => void;
};

const UserContext = createContext<UserContextValue | null>(null);

export function UserProvider({
  user,
  setUser = () => {},
  children,
}: {
  user: User;
  setUser?: (user: User) => void;
  children: React.ReactNode;
}) {
  return <UserContext.Provider value={{ user, setUser }}>{children}</UserContext.Provider>;
}

/** Current authenticated user, for components below <Layout> that aren't
 * reachable via prop-drilling (the gallery hub tree in particular). Existing
 * workflow components keep receiving `role` as an explicit prop this is
 * additive, not a forced migration. */
export function useUser(): User {
  const ctx = useContext(UserContext);
  if (!ctx) throw new Error("useUser() called outside <UserProvider>");
  return ctx.user;
}

export function useSetUser(): (user: User) => void {
  const ctx = useContext(UserContext);
  if (!ctx) throw new Error("useSetUser() called outside <UserProvider>");
  return ctx.setUser;
}

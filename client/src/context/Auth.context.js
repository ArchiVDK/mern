import {createContext} from 'react';

function noop() {}

export const AuthContext = createContext({
  token: null,
  userid: null,
  login: noop,
  logout: noop,
  isAuth: false,
});

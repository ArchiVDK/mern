import React, {useEffect, useState, useContext} from 'react';
import {AuthContext} from '../context/Auth.context';
import {useHttp} from '../hooks/http.hook';
import {useMessage} from '../hooks/message.hook';

export const AuthPage = () => {
  const auth = useContext(AuthContext);
  const message = useMessage();
  const {loading, request, error, clearError} = useHttp();
  const [form, setform] = useState({
    email: '',
    password: '',
  });
  const changeHandler = (event) => {
    setform({...form, [event.target.name]: event.target.value});
  };

  useEffect(() => {
    message(error);
    clearError();
  }, [error, message, clearError]);

  useEffect(() => {
    window.M.updateTextFields();
  }, []);

  const registerHandler = async () => {
    try {
      const data = await request('/api/auth/register', 'POST', {...form});
      message(data.message);
    } catch (e) {}
  };
  const loginHandler = async () => {
    try {
      const data = await request('/api/auth/login', 'POST', {...form});
      auth.login(data.token, data.userid);
    } catch (e) {}
  };

  return (
    <div className="row">
      <div className="col s6 offset-s3">
        <h1>Сократи ссылку</h1>
        <div className="card blue darken-1">
          <div className="card-content white-text">
            <span className="card-title">Авторизация</span>
            <div>
              <div className="input-field">
                <input
                  placeholder="Введите email"
                  id="email"
                  type="text"
                  name="email"
                  className="yellow-input"
                  value={form.email}
                  onChange={changeHandler}
                />
                <label htmlFor="email">Email</label>
              </div>
            </div>
            <div>
              <div className="input-field">
                <input
                  placeholder="Введите пароль"
                  id="password"
                  type="password"
                  name="password"
                  className="yellow-input"
                  value={form.password}
                  onChange={changeHandler}
                />
                <label htmlFor="password">Пароль</label>
              </div>
            </div>
          </div>
          <div className="card-action">
            <button
              className="btn yellow darken-4"
              style={{marginRight: 10}}
              disabled={loading}
              onClick={loginHandler}
            >
              Войти
            </button>
            <button
              className="btn grey ligthen-1 black-text"
              onClick={registerHandler}
              disabled={loading}
            >
              Регистрация
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

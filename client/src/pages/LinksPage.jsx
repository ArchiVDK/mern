import React, {useCallback, useContext, useEffect, useState} from 'react';
import {LinksList} from '../components/LinksList';
import {Loader} from '../components/Loader';
import {AuthContext} from '../context/Auth.context';
import {useHttp} from '../hooks/http.hook';

export const LinksPage = () => {
  const [links, setlinks] = useState([]);
  const {loading, request} = useHttp();
  const {token} = useContext(AuthContext);

  const fetchLinks = useCallback(async () => {
    try {
      const fetched = await request('/api/link', 'GET', null, {
        Authorization: `Bearer ${token}`,
      });
      setlinks(fetched);
    } catch (e) {}
  }, [token, request]);

  useEffect(() => {
    fetchLinks();
  }, [fetchLinks]);

  if (loading) {
    return <Loader />;
  }

  return <>{!loading && <LinksList links={links} />}</>;
};

// ★ 앱 사용 칸 + 통합본에서 로그인 없이 열기 — App보다 먼저 읽혀야 해서 맨 위에 둡니다
import { AppAccessGate } from './appGate.jsx';
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <AppAccessGate>
      <App />
    </AppAccessGate>
  </React.StrictMode>,
);

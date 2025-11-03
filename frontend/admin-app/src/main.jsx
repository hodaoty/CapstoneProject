import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'

// 1. IMPORT BrowserRouter TỪ THƯ VIỆN ROUTER
import { BrowserRouter } from 'react-router-dom'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    {/* 2. BỌC <App /> CỦA BẠN BÊN TRONG <BrowserRouter> */}
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
)
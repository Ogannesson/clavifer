import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';
import { App } from './app';
import { ConfirmProvider } from './ui';

createRoot(document.querySelector<HTMLDivElement>('#app')!).render(
  <StrictMode>
    <ConfirmProvider>
      {/* This module is the entry script (/assets/index-<hash>.js once built), which a deployment replaces. */}
      <App entry={new URL(import.meta.url).pathname} />
    </ConfirmProvider>
  </StrictMode>,
);

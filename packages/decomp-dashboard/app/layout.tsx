import type { ReactNode } from 'react';
import './globals.css';

export const metadata = {
  title: 'open-empires · decompilation',
  description: 'Live progress of the Age of Empires II decompilation',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

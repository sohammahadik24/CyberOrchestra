import React from 'react';

interface HeaderProps {
  pageTitle: string;
  pageSubtitle?: string;
  rightContent?: React.ReactNode;
}

export const Header: React.FC<HeaderProps> = ({ pageTitle, pageSubtitle, rightContent }) => (
  <header className="app-page-header">
    <div className="app-page-heading">
      <h1>{pageTitle}</h1>
      {pageSubtitle && <p>{pageSubtitle}</p>}
    </div>
    {rightContent && <div className="app-page-actions">{rightContent}</div>}
  </header>
);

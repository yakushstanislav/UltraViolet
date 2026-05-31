import type { ReactNode } from 'react';

type FieldLabelProps = {
  children: ReactNode;
  required?: boolean;
  htmlFor?: string;
};

export function FieldLabel({ children, required, htmlFor }: FieldLabelProps) {
  return (
    <span
      className={required ? 'field-label field-label--required' : 'field-label'}
    >
      {htmlFor !== undefined ? (
        <label htmlFor={htmlFor}>{children}</label>
      ) : (
        children
      )}
    </span>
  );
}

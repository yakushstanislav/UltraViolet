export function fieldErrorId(fieldName: string): string {
  return `field-error-${fieldName}`;
}

export type FieldAriaProps = {
  'aria-invalid'?: boolean;
  'aria-describedby'?: string;
};

export function fieldAria(
  fieldName: string,
  hasError: boolean
): FieldAriaProps {
  if (!hasError) {
    return {};
  }

  return {
    'aria-invalid': true,
    'aria-describedby': fieldErrorId(fieldName),
  };
}

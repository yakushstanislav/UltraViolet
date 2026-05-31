type HttpMethodBadgeProps = {
  method: string;
};

const KNOWN_METHODS = new Set([
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'HEAD',
  'OPTIONS',
]);

export function HttpMethodBadge({ method }: HttpMethodBadgeProps) {
  const upper = method.toUpperCase();
  const variant = KNOWN_METHODS.has(upper) ? upper.toLowerCase() : 'other';

  return (
    <span className={`status http-method http-method-${variant}`}>
      {upper}
    </span>
  );
}

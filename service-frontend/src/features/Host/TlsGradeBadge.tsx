type Props = {
  grade: string;
};

const gradeClass = (grade: string): string => {
  switch (grade.toUpperCase()) {
    case 'A':
      return 'tls-grade tls-grade-a';
    case 'B':
      return 'tls-grade tls-grade-b';
    case 'C':
      return 'tls-grade tls-grade-c';
    case 'F':
      return 'tls-grade tls-grade-f';
    default:
      return 'tls-grade tls-grade-unknown';
  }
};

export const TlsGradeBadge = ({ grade }: Props) => (
  <span className={gradeClass(grade)} title={`TLS grade ${grade}`}>
    {grade.toUpperCase()}
  </span>
);

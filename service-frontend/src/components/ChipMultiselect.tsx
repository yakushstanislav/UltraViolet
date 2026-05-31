export type ChipOption<T extends string> = {
  value: T;
  label: string;
};

type ChipMultiselectProps<T extends string> = {
  label?: string;
  options: ChipOption<T>[];
  selected: T[];
  onToggle: (value: T) => void;
};

export function ChipMultiselect<T extends string>({
  label,
  options,
  selected,
  onToggle,
}: ChipMultiselectProps<T>) {
  return (
    <div className="chip-multiselect" role="group" aria-label={label}>
      {label !== undefined && label !== '' && (
        <span className="search-field-label">{label}</span>
      )}
      <div className="chip-multiselect-wrap">
        {options.map((option) => {
          const active = selected.includes(option.value);

          return (
            <button
              aria-pressed={active}
              className={
                active
                  ? 'chip-multiselect-chip chip-multiselect-chip-active'
                  : 'chip-multiselect-chip'
              }
              key={option.value}
              onClick={() => onToggle(option.value)}
              type="button"
            >
              {option.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}

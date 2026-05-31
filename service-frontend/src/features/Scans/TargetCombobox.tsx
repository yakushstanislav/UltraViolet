import { useRef, useState } from 'react';

type Props = {
  value: string;
  onChange: (v: string) => void;
  onBlur: () => void;
  inputRef: React.Ref<HTMLInputElement>;
  suggestions: string[];
  placeholder?: string;
  ariaDescribedBy?: string;
  ariaInvalid?: boolean;
};

export function TargetCombobox({
  value,
  onChange,
  onBlur,
  inputRef,
  suggestions,
  placeholder,
  ariaDescribedBy,
  ariaInvalid,
}: Props) {
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);
  const containerRef = useRef<HTMLDivElement>(null);

  const filtered = suggestions.filter(
    (s) => value === '' || s.toLowerCase().includes(value.toLowerCase())
  );

  const handleSelect = (s: string) => {
    onChange(s);
    setDropdownOpen(false);
    setActiveIndex(-1);
  };

  const handleContainerBlur = (e: React.FocusEvent) => {
    if (!containerRef.current?.contains(e.relatedTarget as Node)) {
      setDropdownOpen(false);
      setActiveIndex(-1);
      onBlur();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (!dropdownOpen || filtered.length === 0) {
      return;
    }

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActiveIndex((i) => (i + 1) % filtered.length);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActiveIndex((i) => (i <= 0 ? filtered.length - 1 : i - 1));
    } else if (e.key === 'Enter' && activeIndex >= 0) {
      e.preventDefault();
      const choice = filtered[activeIndex];
      if (choice !== undefined) {
        handleSelect(choice);
      }
    } else if (e.key === 'Escape') {
      setDropdownOpen(false);
      setActiveIndex(-1);
      onBlur();
    }
  };

  return (
    <div
      className="target-combobox"
      onBlur={handleContainerBlur}
      ref={containerRef}
    >
      <input
        aria-describedby={ariaDescribedBy}
        aria-invalid={ariaInvalid}
        autoComplete="off"
        type="text"
        onChange={(e) => {
          onChange(e.target.value);
          setActiveIndex(-1);
          setDropdownOpen(true);
        }}
        onFocus={() => {
          if (filtered.length > 0) {
            setDropdownOpen(true);
          }
        }}
        onKeyDown={handleKeyDown}
        placeholder={placeholder}
        ref={inputRef}
        value={value}
      />
      {dropdownOpen && filtered.length > 0 && (
        <ul className="target-combobox-list" role="listbox">
          {filtered.map((s, i) => (
            <li
              className={`target-combobox-item${i === activeIndex ? ' target-combobox-item-active' : ''}`}
              key={s}
              onMouseDown={(e) => {
                e.preventDefault();
                handleSelect(s);
              }}
              role="option"
            >
              {s}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

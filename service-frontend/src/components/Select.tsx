import * as Popover from '@radix-ui/react-popover';
import clsx from 'clsx';
import { Check, ChevronDown } from 'lucide-react';
import {
  type KeyboardEvent,
  type ReactNode,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from 'react';

export type SelectOption = {
  value: string;
  label: ReactNode;
  disabled?: boolean;
};

export type SelectGroup = {
  label: ReactNode;
  options: SelectOption[];
};

export type SelectItem = SelectOption | SelectGroup;

type SelectProps = {
  options: SelectItem[];
  value: string;
  onChange: (value: string) => void;
  placeholder?: ReactNode;
  name?: string;
  id?: string;
  'aria-label'?: string;
  disabled?: boolean;
  compact?: boolean;
  className?: string;
  triggerClassName?: string;
  contentClassName?: string;
  matchTriggerWidth?: boolean;
};

function isGroup(item: SelectItem): item is SelectGroup {
  return Array.isArray((item as SelectGroup).options);
}

function flattenOptions(items: SelectItem[]): SelectOption[] {
  const out: SelectOption[] = [];

  for (const item of items) {
    if (isGroup(item)) {
      out.push(...item.options);
    } else {
      out.push(item);
    }
  }

  return out;
}

export function Select({
  options,
  value,
  onChange,
  placeholder,
  name,
  id,
  'aria-label': ariaLabel,
  disabled = false,
  compact = false,
  className,
  triggerClassName,
  contentClassName,
  matchTriggerWidth = true,
}: SelectProps) {
  const reactId = useId();
  const triggerId = id ?? `${reactId}-trigger`;
  const listId = `${reactId}-listbox`;

  const [open, setOpen] = useState(false);
  const listRef = useRef<HTMLUListElement>(null);

  const flat = useMemo(() => flattenOptions(options), [options]);
  const selected = flat.find((option) => option.value === value);
  const [activeIndex, setActiveIndex] = useState(0);

  useEffect(() => {
    if (!open) {
      return;
    }

    const index = flat.findIndex(
      (option) => option.value === value && !option.disabled
    );

    setActiveIndex(index >= 0 ? index : 0);
  }, [flat, open, value]);

  useEffect(() => {
    if (!open) {
      return;
    }

    const frame = requestAnimationFrame(() => {
      listRef.current?.focus();
    });

    return () => cancelAnimationFrame(frame);
  }, [open]);

  useEffect(() => {
    if (!open) {
      return;
    }

    document
      .getElementById(`${listId}-opt-${activeIndex}`)
      ?.scrollIntoView({ block: 'nearest' });
  }, [activeIndex, listId, open]);

  const moveActive = (delta: number) => {
    if (flat.length === 0) {
      return;
    }

    setActiveIndex((prev) => {
      let next = prev;

      for (let step = 0; step < flat.length; step += 1) {
        next = (next + delta + flat.length) % flat.length;

        if (!flat[next]?.disabled) {
          return next;
        }
      }

      return prev;
    });
  };

  const commit = (index: number) => {
    const option = flat[index];

    if (!option || option.disabled) {
      return;
    }

    onChange(option.value);
    setOpen(false);
  };

  const onListKeyDown = (event: KeyboardEvent<HTMLUListElement>) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      moveActive(1);

      return;
    }

    if (event.key === 'ArrowUp') {
      event.preventDefault();
      moveActive(-1);

      return;
    }

    if (event.key === 'Home') {
      event.preventDefault();
      setActiveIndex(0);

      return;
    }

    if (event.key === 'End') {
      event.preventDefault();
      setActiveIndex(Math.max(0, flat.length - 1));

      return;
    }

    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      commit(activeIndex);
    }
  };

  let runningIndex = 0;

  const renderOption = (option: SelectOption, index: number) => {
    const isSelected = option.value === value;
    const isActive = index === activeIndex;

    return (
      <li
        aria-disabled={option.disabled || undefined}
        aria-selected={isSelected}
        className={clsx(
          'uv-select-option',
          isActive && 'uv-select-option--active',
          isSelected && 'uv-select-option--selected',
          option.disabled && 'uv-select-option--disabled'
        )}
        id={`${listId}-opt-${index}`}
        key={option.value}
        onMouseDown={(event) => event.preventDefault()}
        onMouseEnter={() => {
          if (!option.disabled) {
            setActiveIndex(index);
          }
        }}
        onMouseUp={() => commit(index)}
        role="option"
      >
        <span className="uv-select-option-text">{option.label}</span>
        {isSelected ? (
          <Check
            aria-hidden
            className="uv-select-option-check"
            size={14}
            strokeWidth={2.5}
          />
        ) : null}
      </li>
    );
  };

  return (
    <Popover.Root
      onOpenChange={(next) => {
        if (!disabled) {
          setOpen(next);
        }
      }}
      open={disabled ? false : open}
    >
      <span
        className={clsx(
          'uv-select',
          compact && 'uv-select--compact',
          disabled && 'uv-select--disabled',
          className
        )}
      >
        {name !== undefined ? (
          <input name={name} type="hidden" value={value} />
        ) : null}
        <Popover.Trigger asChild>
          <button
            aria-controls={listId}
            aria-expanded={open}
            aria-haspopup="listbox"
            aria-label={ariaLabel}
            className={clsx('uv-select-trigger', triggerClassName)}
            disabled={disabled}
            id={triggerId}
            type="button"
          >
            <span className="uv-select-trigger-text">
              {selected ? selected.label : placeholder}
            </span>
            <ChevronDown
              aria-hidden
              className="uv-select-trigger-caret"
              size={compact ? 14 : 16}
            />
          </button>
        </Popover.Trigger>
        <Popover.Portal>
          <Popover.Content
            align="start"
            className={clsx(
              'uv-select-content',
              matchTriggerWidth && 'uv-select-content--match-trigger',
              contentClassName
            )}
            collisionPadding={12}
            onOpenAutoFocus={(event) => event.preventDefault()}
            side="bottom"
            sideOffset={6}
          >
            <ul
              aria-activedescendant={
                flat.length > 0 ? `${listId}-opt-${activeIndex}` : undefined
              }
              className="uv-select-list"
              id={listId}
              onKeyDown={onListKeyDown}
              ref={listRef}
              role="listbox"
              tabIndex={-1}
            >
              {options.map((item, itemIdx) => {
                if (isGroup(item)) {
                  return (
                    <li
                      className="uv-select-group"
                      key={`group-${itemIdx}`}
                      role="presentation"
                    >
                      <div
                        className="uv-select-group-label"
                        role="presentation"
                      >
                        {item.label}
                      </div>
                      <ul
                        aria-label={
                          typeof item.label === 'string' ? item.label : undefined
                        }
                        className="uv-select-group-list"
                        role="group"
                      >
                        {item.options.map((option) =>
                          renderOption(option, runningIndex++)
                        )}
                      </ul>
                    </li>
                  );
                }

                return renderOption(item, runningIndex++);
              })}
            </ul>
          </Popover.Content>
        </Popover.Portal>
      </span>
    </Popover.Root>
  );
}

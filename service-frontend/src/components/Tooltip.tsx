import * as TooltipPrimitive from '@radix-ui/react-tooltip';
import type { ReactNode } from 'react';

import { useCanHover } from '@/hooks/useBreakpoint';

type TooltipSide = 'top' | 'right' | 'bottom' | 'left';

type TooltipProps = {
  label: string;
  side?: TooltipSide;
  children: ReactNode;
};

export const TooltipProvider = TooltipPrimitive.Provider;

export function Tooltip({ label, side = 'top', children }: TooltipProps) {
  const canHover = useCanHover();

  if (!canHover) {
    return <>{children}</>;
  }

  return (
    <TooltipPrimitive.Root>
      <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
      <TooltipPrimitive.Portal>
        <TooltipPrimitive.Content
          className="uv-tooltip"
          side={side}
          sideOffset={6}
        >
          {label}
          <TooltipPrimitive.Arrow className="uv-tooltip-arrow" />
        </TooltipPrimitive.Content>
      </TooltipPrimitive.Portal>
    </TooltipPrimitive.Root>
  );
}

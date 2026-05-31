# UltraViolet UI Smoke Checklist

## Core flows

- Login as `viewer`, `operator`, and `admin`; verify role badge and access boundaries.
- Switch theme in topbar and reload page; verify theme persists.
- Open/close mobile navigation on narrow viewport and verify backdrop behavior.

## Search

- Submit search with only `q`, then with advanced filters; verify URL params update.
- Use `Reset filters`; verify results refresh and params clear.
- Verify `Export CSV` works with active query params.
- Check long match fragments wrap inside table cell without layout break.

## Scans

- Open `New scan` dialog, validate required fields, and submit valid scan.
- Confirm scan row status badge changes and stats render in readable format.
- Verify `Refresh` button and 3s polling both update table state.

## Dashboard / Host / Ops / Insights

- Dashboard cards: loading, normal, and error states.
- Host page: metadata row, service panels, HTTP body area, TLS section.
- Operations and Insights forms: create flow for operator/admin; read-only messaging for viewer.

## Responsive + accessibility

- Test at widths: `1440`, `1024`, `768`, `390`.
- Keyboard only: focus ring is visible on nav, buttons, inputs, and links.
- Ensure contrast is acceptable in both light and dark themes for status/error/notice blocks.

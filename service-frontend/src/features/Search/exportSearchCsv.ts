import { apiClient } from '@services/apiClient';

export type ExportSearchCsvError =
  | { kind: 'auth' }
  | { kind: 'failed'; cause: unknown };

/**
 * Streams the current search result set as a CSV file and triggers a browser
 * download. The CSV is fetched with `limit=10000` and without `page` so the
 * single download spans the full result set. Auth failures are silenced — the
 * router-level interceptor handles login redirect; everything else surfaces
 * through `onError` so the caller can show a toast.
 */
export async function exportSearchCsv(
  searchParams: URLSearchParams,
  onError: (err: ExportSearchCsvError) => void
): Promise<void> {
  const exportParams = new URLSearchParams(searchParams);
  exportParams.set('format', 'csv');
  exportParams.set('limit', '10000');
  exportParams.delete('page');

  try {
    const response = await apiClient.get<Blob>(
      `/v1/search?${exportParams.toString()}`,
      { responseType: 'blob' }
    );

    const objectURL = URL.createObjectURL(response.data);
    const a = document.createElement('a');
    a.href = objectURL;
    a.download = 'uv-search.csv';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(objectURL);
  } catch (err: unknown) {
    const status =
      typeof err === 'object' &&
      err !== null &&
      'response' in err &&
      typeof (err as { response?: { status?: number } }).response?.status ===
        'number'
        ? (err as { response: { status: number } }).response.status
        : undefined;

    if (status === 401 || status === 403) {
      onError({ kind: 'auth' });

      return;
    }

    onError({ kind: 'failed', cause: err });
  }
}

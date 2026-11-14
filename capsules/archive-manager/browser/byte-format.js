// Decimal file sizes. A transfer keeps the unit selected by its total.
const UNITS = ["B", "KB", "MB", "GB", "TB"];
const count = value => Number.isFinite(Number(value)) ? Math.max(0, Number(value)) : 0;
function rank(bytes, rounding = Math.round) {
  let unit = 0;
  while (unit < UNITS.length - 1 && (unit === 0 ? bytes >= 1000 : rounding(bytes * 10 / 1000 ** unit) >= 10000)) unit++;
  return unit;
}
function inUnit(bytes, unit, rounding = Math.round) {
  const precision = unit === 3 ? 100 : 10;
  return `${unit ? (rounding(bytes * precision / 1000 ** unit) / precision).toFixed(unit === 3 ? 2 : 1) : Math.floor(bytes)} ${UNITS[unit]}`;
}
export function formatBytes(value, rounding = Math.round) {
  if (value === null || value === undefined || value === "" || !Number.isFinite(Number(value)) || Number(value) < 0) return "Size unknown";
  const bytes = count(value);
  return inUnit(bytes, rank(bytes, rounding), rounding);
}
export function formatBytesOf(completed, total) {
  const bytes = count(total), unit = rank(bytes);
  const done = count(completed), size = inUnit(bytes, unit);
  let received = inUnit(Math.min(done, bytes), unit);
  // Reserve equal displayed counts for true byte completion at every unit.
  if (done !== bytes && received === size) {
    const precision = unit === 0 ? 1 : unit === 3 ? 100 : 10;
    const step = 1000 ** unit / precision;
    received = inUnit(Math.max(0, (Math.round(bytes / step) - 1) * step), unit);
  }
  return `${received} of ${size}`;
}

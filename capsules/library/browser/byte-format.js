// Decimal file sizes. A transfer keeps the unit selected by its total.
const UNITS = ["B", "KB", "MB", "GB", "TB"];
const count = value => Number.isFinite(Number(value)) ? Math.max(0, Number(value)) : 0;
function rank(bytes, rounding = Math.round) {
  let unit = 0;
  while (unit < UNITS.length - 1 && (unit === 0 ? bytes >= 1000 : rounding(bytes * 10 / 1000 ** unit) >= 10000)) unit++;
  return unit;
}
function inUnit(bytes, unit, rounding = Math.round) {
  return `${unit ? (rounding(bytes * 10 / 1000 ** unit) / 10).toFixed(1) : Math.floor(bytes)} ${UNITS[unit]}`;
}
export function formatBytes(value, rounding = Math.round) {
  if (value === null || value === undefined || value === "" || !Number.isFinite(Number(value)) || Number(value) < 0) return "Size unknown";
  const bytes = count(value);
  return inUnit(bytes, rank(bytes, rounding), rounding);
}
export function formatBytesOf(completed, total) {
  const bytes = count(total), unit = rank(bytes);
  return `${inUnit(Math.min(count(completed), bytes), unit)} of ${inUnit(bytes, unit)}`;
}

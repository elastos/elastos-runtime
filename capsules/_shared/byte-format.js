// Decimal file sizes. A transfer keeps the unit selected by its total.
const UNITS = ["B", "KB", "MB", "GB", "TB"];
const count = value => Number.isFinite(Number(value)) ? Math.max(0, Number(value)) : 0;
function rank(bytes) {
  let unit = 0;
  while (unit < UNITS.length - 1 && bytes >= 1000 ** (unit + 1)) unit++;
  return unit;
}
function inUnit(bytes, unit) {
  return `${unit ? (Math.round(bytes * 10 / 1000 ** unit) / 10).toFixed(1) : Math.floor(bytes)} ${UNITS[unit]}`;
}
export function formatBytes(value) {
  const bytes = count(value);
  return inUnit(bytes, rank(bytes));
}
export function formatBytesOf(completed, total) {
  const bytes = count(total), unit = rank(bytes);
  return `${inUnit(Math.min(count(completed), bytes), unit)} of ${inUnit(bytes, unit)}`;
}

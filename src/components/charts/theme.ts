/**
 * Chart palette.
 *
 * Three categorical slots, validated with the dataviz validator against both
 * surfaces on the all-pairs list (scatter puts every pair on screen at once, so
 * the adjacent-pair list does not apply):
 *   light  worst CVD ΔE 9.2, worst normal-vision ΔE 24.0
 *   dark   worst CVD ΔE 9.4, worst normal-vision ΔE 20.9
 *
 * `#1baf7a` sits below 3:1 on the light surface, so every chart using it ships
 * visible direct labels and a table view — the relief rule. Nothing here encodes
 * meaning by colour alone: series carry a distinct marker shape as well as a hue,
 * and every chart is accompanied by the same numbers in a table.
 */

export const SERIES_LIGHT = ['#2a78d6', '#eb6834', '#1baf7a'] as const;
export const SERIES_DARK = ['#3987e5', '#d95926', '#199e70'] as const;

/** Reserved status colours, never reused as a series hue. */
export const STATUS = {
  good: '#008300',
  warning: '#eda100',
  critical: '#e34948',
} as const;

/** Marker shapes give every series a second, non-colour channel. */
export const SHAPES = ['circle', 'square', 'triangle'] as const;

export function seriesColor(index: number, dark: boolean): string {
  const palette = dark ? SERIES_DARK : SERIES_LIGHT;
  return palette[index % palette.length] ?? palette[0];
}

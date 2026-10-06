/**
 * TOUCHSTONE design tokens. Every colour is an RGB channel triple defined in
 * src/index.css (light on :root, dark under [data-theme="dark"]) so opacity
 * modifiers such as `bg-sage/15` compose. Never define a token with its own
 * alpha: Tailwind's `/NN` modifier would replace it.
 *
 * Visual grammar (used everywhere, not decoration):
 *   solid fill      evidence observed
 *   diagonal hatch  outside the public evidence boundary (not externally verifiable)
 *   dashed outline  could not be determined (unknown / missing)
 *
 * Accent roles: sage = evidence supports, marigold = partial, iris = evidence
 * boundary, vermilion = observed deviation / data error, plum = disputes.
 * `*-ink` variants are the text-safe tones (>= 4.5:1 in both themes).
 */
const rgb = (name) => `rgb(var(--${name}) / <alpha-value>)`

/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: ['selector', '[data-theme="dark"]'],
  theme: {
    screens: {
      xs: '400px',
      sm: '640px',
      md: '768px',
      lg: '1024px',
      xl: '1280px',
      '2xl': '1440px',
    },
    extend: {
      colors: {
        paper: { DEFAULT: rgb('paper'), 2: rgb('paper-2'), 3: rgb('paper-3') },
        surface: { DEFAULT: rgb('surface'), raised: rgb('surface-raised') },
        ink: { DEFAULT: rgb('ink'), 2: rgb('ink-2'), 3: rgb('ink-3') },
        line: { DEFAULT: rgb('line'), strong: rgb('line-strong') },
        slab: { DEFAULT: rgb('slab'), 2: rgb('slab-2'), ink: rgb('slab-ink'), dim: rgb('slab-dim'), line: rgb('slab-line'), iris: rgb('slab-iris') },
        vermilion: { DEFAULT: rgb('vermilion'), ink: rgb('vermilion-ink') },
        marigold: { DEFAULT: rgb('marigold'), ink: rgb('marigold-ink') },
        sage: { DEFAULT: rgb('sage'), ink: rgb('sage-ink') },
        iris: { DEFAULT: rgb('iris'), ink: rgb('iris-ink') },
        plum: { DEFAULT: rgb('plum'), ink: rgb('plum-ink') },
        focus: rgb('focus'),
      },
      fontFamily: {
        sans: ['Manrope', 'ui-sans-serif', 'system-ui', 'Segoe UI', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'Cascadia Mono', 'Consolas', 'monospace'],
      },
      fontSize: {
        label: ['0.6875rem', { lineHeight: '1rem', letterSpacing: '0.12em', fontWeight: '500' }],
        data: ['0.8125rem', { lineHeight: '1.25rem' }],
        hero: ['clamp(2.6rem, 0.6rem + 6.4vw, 6.25rem)', { lineHeight: '0.95', letterSpacing: '-0.045em', fontWeight: '800' }],
        display: ['clamp(2.25rem, 1rem + 3.8vw, 4.25rem)', { lineHeight: '1', letterSpacing: '-0.04em', fontWeight: '800' }],
        'title-1': ['clamp(1.75rem, 1.25rem + 1.7vw, 2.6rem)', { lineHeight: '1.06', letterSpacing: '-0.032em', fontWeight: '800' }],
        'title-2': ['1.5rem', { lineHeight: '1.2', letterSpacing: '-0.022em', fontWeight: '700' }],
        'title-3': ['1.125rem', { lineHeight: '1.35', letterSpacing: '-0.012em', fontWeight: '700' }],
        lede: ['clamp(1.0625rem, 0.97rem + 0.4vw, 1.3rem)', { lineHeight: '1.55', letterSpacing: '-0.006em' }],
      },
      borderRadius: {
        chip: '8px',
        control: '14px',
        card: '16px',
        panel: '20px',
        hero: '28px',
      },
      boxShadow: {
        hairline: '0 0 0 1px rgb(var(--line) / 1)',
        soft: '0 1px 0 rgb(var(--shadow) / 0.04), 0 1px 2px rgb(var(--shadow) / 0.05), 0 12px 30px -18px rgb(var(--shadow) / 0.22)',
        lift: '0 1px 0 rgb(var(--shadow) / 0.05), 0 4px 10px -4px rgb(var(--shadow) / 0.12), 0 22px 48px -24px rgb(var(--shadow) / 0.3)',
        overlay: '0 2px 6px rgb(var(--shadow) / 0.10), 0 32px 80px -24px rgb(var(--shadow) / 0.45)',
      },
      transitionTimingFunction: {
        'out-quart': 'cubic-bezier(0.25, 1, 0.5, 1)',
        'out-expo': 'cubic-bezier(0.16, 1, 0.3, 1)',
      },
      maxWidth: {
        prose: '68ch',
        page: '1360px',
      },
    },
  },
  plugins: [],
}

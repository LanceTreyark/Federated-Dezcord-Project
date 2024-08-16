/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./views/**/*.{ejs,js}",
    "./node_modules/flowbite/**/*.js"
  ],
  theme: {
    extend: {
      colors: {
        zinc: {
          50: '#f8fafc',
          100: '#f1f5f9',
          200: '#e2e8f0',
          300: '#cbd5e1',
          400: '#94a3b8',
          500: '#64748b',
          600: '#475569',
          700: '#334155',
          800: '#1e293b',
          900: '#0f172a',
          950: '#0a0e17',
        },
      },
      typography: ({ theme }) => ({
        orange: {
          css: {
            '--tw-format-body': theme('colors.orange[500]'),
            '--tw-format-headings': theme('colors.orange[900]'),
            '--tw-format-lead': theme('colors.orange[500]'),
            '--tw-format-links': theme('colors.orange[600]'),
            '--tw-format-bold': theme('colors.orange[900]'),
            '--tw-format-counters': theme('colors.orange[500]'),
            '--tw-format-bullets': theme('colors.orange[500]'),
            '--tw-format-hr': theme('colors.orange[200]'),
            '--tw-format-quotes': theme('colors.orange[900]'),
            '--tw-format-quote-borders': theme('colors.orange[300]'),
            '--tw-format-captions': theme('colors.orange[700]'),
            '--tw-format-code': theme('colors.orange[900]'),
            '--tw-format-code-bg': theme('colors.orange[50]'),
            '--tw-format-pre-code': theme('colors.orange[100]'),
            '--tw-format-pre-bg': theme('colors.orange[900]'),
            '--tw-format-th-borders': theme('colors.orange[300]'),
            '--tw-format-td-borders': theme('colors.orange[200]'),
            '--tw-format-th-bg': theme('colors.orange[50]'),
            '--tw-format-invert-body': theme('colors.orange[200]'),
            '--tw-format-invert-headings': theme('colors.white'),
            '--tw-format-invert-lead': theme('colors.orange[300]'),
            '--tw-format-invert-links': theme('colors.white'),
            '--tw-format-invert-bold': theme('colors.white'),
            '--tw-format-invert-counters': theme('colors.orange[400]'),
            '--tw-format-invert-bullets': theme('colors.orange[600]'),
            '--tw-format-invert-hr': theme('colors.orange[700]'),
            '--tw-format-invert-quotes': theme('colors.pink[100]'),
            '--tw-format-invert-quote-borders': theme('colors.orange[700]'),
            '--tw-format-invert-captions': theme('colors.orange[400]'),
            '--tw-format-invert-code': theme('colors.white'),
            '--tw-format-invert-pre-code': theme('colors.orange[300]'),
            '--tw-format-invert-pre-bg': 'rgb(0 0 0 / 50%)',
            '--tw-format-invert-th-borders': theme('colors.orange[600]'),
            '--tw-format-invert-td-borders': theme('colors.orange[700]'),
            '--tw-format-invert-th-bg': theme('colors.orange[700]'),
          },
        },
      }),
    },
  },
  plugins: [
    require('flowbite/plugin'),
    require('flowbite-typography'),
  ],
}

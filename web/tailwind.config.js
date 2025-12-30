/** @type {import('tailwindcss').Config} */
module.exports = {
    content: ["./src/**/*.{html,ts,js}"],
    theme: {
        extend: {
            colors: {
                'brand-dark': '#1a1a2e',
                'brand-light': '#16213e',
                'brand-accent': '#0f3460',
                'brand-primary': '#e94560',
            },
        },
    },
    plugins: [],
}

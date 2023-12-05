import dts from 'bun-plugin-dts'

await Bun.build({
  entrypoints: ['./src/lib/authPlugin.ts'],
  outdir: './dist',
  plugins: [
    dts()
  ],
})
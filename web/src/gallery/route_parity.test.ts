import { describe, expect, it } from 'vitest'
import mainSource from '../main.tsx?raw'
import { BUILTIN_TILES } from './tile_registry'

describe('built-in route inventory', () => {
  it('has one gallery tile for every static workflow route', () => {
    const routes = new Set(
      [...mainSource.matchAll(/<Route path="([^"]+)"/g)]
        .map((match) => match[1])
        .filter((path) => path.startsWith('/') && path !== '/' && !path.includes(':'))
        .filter((path) => !['/hub', '/detection-admin', '/services'].includes(path)),
    )
    const tiles = new Set(BUILTIN_TILES.map((tile) => tile.href))
    expect([...routes].filter((path) => !tiles.has(path))).toEqual([])
    expect([...tiles].filter((path) => !routes.has(path))).toEqual([])
  })
})

import { useCallback, useEffect, useRef, useState } from 'react'

export interface AsyncData<T> {
  data: T | null
  loading: boolean
  error: string | null
  refresh: () => Promise<void>
}

/**
 * Fetch data with cancellation: state is never written after unmount or
 * after a newer request has started, and `refresh` always runs the latest fn.
 */
export function useAsyncData<T>(fn: () => Promise<T>, deps: unknown[]): AsyncData<T> {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const fnRef = useRef(fn)
  const runId = useRef(0)
  const mounted = useRef(true)

  useEffect(() => {
    fnRef.current = fn
  })

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  const load = useCallback(async () => {
    const id = ++runId.current
    setLoading(true)
    setError(null)
    try {
      const result = await fnRef.current()
      if (mounted.current && id === runId.current) {
        setData(result)
      }
    } catch (err) {
      if (mounted.current && id === runId.current) {
        setError(err instanceof Error ? err.message : String(err))
      }
    } finally {
      if (mounted.current && id === runId.current) {
        setLoading(false)
      }
    }
  }, [])

  useEffect(() => {
    void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  return { data, loading, error, refresh: load }
}

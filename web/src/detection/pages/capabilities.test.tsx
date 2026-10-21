import '@testing-library/jest-dom/vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const apiMock = vi.hoisted(() => ({
  listModels: vi.fn(),
  getModelDrift: vi.fn(),
  listModelVersions: vi.fn(),
  listTrainingJobs: vi.fn(),
  listNotificationSettings: vi.fn(),
  listDeployments: vi.fn(),
  listNotificationOutbox: vi.fn(),
  retryNotificationOutbox: vi.fn(),
}))

vi.mock('../api/client', () => ({ api: apiMock }))

import { Admin } from './Admin'
import { Models } from './Models'

afterEach(() => cleanup())

beforeEach(() => {
  cleanup()
  vi.clearAllMocks()
  apiMock.getModelDrift.mockResolvedValue({
    model_id: 'host-state-model',
    overall_score: 0,
    features: [],
    recommendation: 'not reported',
    computed_at: new Date().toISOString(),
  })
  apiMock.listModelVersions.mockResolvedValue([])
  apiMock.listTrainingJobs.mockResolvedValue([])
  apiMock.listNotificationSettings.mockResolvedValue([])
  apiMock.listDeployments.mockResolvedValue([])
  apiMock.retryNotificationOutbox.mockResolvedValue({ status: 'pending' })
})

describe('capability surfaces', () => {
  it('renders host-state as inference-only with training disabled', async () => {
    apiMock.listModels.mockResolvedValue([
      {
        model_id: 'host-state-model',
        name: 'Host State Model',
        modality: 'host_state',
        version: '0.1.0',
        status: 'ready',
        last_inference: null,
        findings_24h: null,
        avg_latency_ms: null,
        aliases: [],
        artifact_state: 'external',
        trainable: false,
        capability_reason: 'inference-only; no reviewed host-state trainer is available',
      },
    ])

    render(
      <MemoryRouter initialEntries={['/models/host-state-model']}>
        <Routes>
          <Route path="/models/:id" element={<Models />} />
        </Routes>
      </MemoryRouter>,
    )

    expect((await screen.findAllByText('Host State Model')).length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: 'Start training' })).toBeDisabled()
    expect(screen.getByText(/no reviewed host-state trainer/i)).toBeInTheDocument()
    expect(screen.getByText('Inference-only')).toBeInTheDocument()
  })

  it('renders failed notification state and retries it', async () => {
    apiMock.listNotificationOutbox
      .mockResolvedValueOnce([
        {
          id: 7,
          tenant_id: 'tenant-acme',
          recipient: 'oncall@example.com',
          subject: 'Critical incident',
          status: 'failed',
          delivery_mode: 'smtp',
          attempt_count: 3,
          last_error: 'connection refused',
          retryable: true,
        },
      ])
      .mockResolvedValueOnce([])

    render(<Admin />)

    expect(await screen.findByText('connection refused')).toBeInTheDocument()
    expect(screen.getByText('smtp')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
    const retryButtons = screen.getAllByRole('button', { name: 'Retry' })
    fireEvent.click(retryButtons[retryButtons.length - 1])
    await waitFor(() => expect(apiMock.retryNotificationOutbox).toHaveBeenCalledWith(7))
  })
})

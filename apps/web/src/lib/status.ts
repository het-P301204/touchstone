/**
 * Display vocabulary for every state the engine produces. Each state has an
 * icon AND a text label; colour is never the only signal. The words are
 * measurement language: never "compliant", "secure", "insecure", "failed".
 */
import {
  Ban,
  CircleCheck,
  CircleDashed,
  CircleDot,
  CircleMinus,
  CircleQuestionMark,
  Contrast,
  EyeOff,
  Hourglass,
  MessageSquareWarning,
  TriangleAlert,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import type {
  CohortPosition,
  CriterionState,
  DisplayState,
  DisputeStatus,
  EvidenceInterpretation,
  FreshnessState,
  VerificationMode,
} from '@touchstone/core/model'

export type Tone = 'sage' | 'marigold' | 'iris' | 'vermilion' | 'plum' | 'stone'

export type StateMeta = { label: string; short?: string; description: string; tone: Tone; icon: LucideIcon; hatch?: boolean; dashed?: boolean }

export const GOAL_STATUS: Record<DisplayState, StateMeta> = {
  VERIFIED: {
    label: 'Evidence supports',
    description: 'Public evidence directly supports the measurement.',
    tone: 'sage',
    icon: CircleCheck,
  },
  PARTIAL: {
    label: 'Partial evidence',
    description: 'Public evidence supports part of the measurement.',
    tone: 'marigold',
    icon: Contrast,
  },
  NOT_VERIFIED: {
    label: 'Evidence incomplete',
    description: 'There is not enough public evidence to establish the measurement.',
    tone: 'stone',
    icon: CircleDashed,
    dashed: true,
  },
  NOT_EXTERNALLY_VERIFIABLE: {
    label: 'Not externally verifiable',
    short: 'Not ext. verifiable',
    description: 'Public evidence cannot meaningfully answer this goal. This is a property of the evidence boundary, not of the vendor.',
    tone: 'iris',
    icon: EyeOff,
    hatch: true,
  },
  DATA_ERROR: {
    label: 'Data error',
    description: 'A source or mapping problem prevented measurement.',
    tone: 'vermilion',
    icon: TriangleAlert,
  },
  DISPUTED: {
    label: 'Disputed',
    description: 'A challenge to this finding is open. The original result is shown unchanged alongside it.',
    tone: 'plum',
    icon: MessageSquareWarning,
  },
}

export const CRITERION_STATE: Record<CriterionState, StateMeta> = {
  MET: { label: 'Met', description: 'The policy text contains this element.', tone: 'sage', icon: CircleCheck },
  PARTIAL: { label: 'Partly met', description: 'The policy supports part of this element.', tone: 'marigold', icon: Contrast },
  NOT_MET: { label: 'Not found', description: 'The policy was read and does not contain this element.', tone: 'stone', icon: CircleMinus },
  CONTRADICTED: {
    label: 'Contradicted',
    description: 'The policy contains language that works against this element. Reported as an observed deviation.',
    tone: 'vermilion',
    icon: Ban,
  },
  UNKNOWN: {
    label: 'Unknown',
    description: 'Could not be determined (no readable policy text). Never counted as met.',
    tone: 'stone',
    icon: CircleQuestionMark,
    dashed: true,
  },
}

export const FRESHNESS_STATE: Record<FreshnessState, StateMeta> = {
  CURRENT: { label: 'Current', description: 'Last successful fetch is within the methodology’s current band.', tone: 'sage', icon: CircleDot },
  AGING: { label: 'Aging', description: 'Older than the current band, still inside the aging band.', tone: 'marigold', icon: Hourglass },
  STALE: { label: 'Stale', description: 'Older than the aging band.', tone: 'vermilion', icon: TriangleAlert },
  UNKNOWN: { label: 'Unknown', description: 'No successful fetch on record.', tone: 'stone', icon: CircleQuestionMark, dashed: true },
}

export const POSITION: Record<CohortPosition, { label: string; tone: Tone }> = {
  ABOVE_PEER_MEDIAN: { label: 'Above peer median on this observable metric', tone: 'sage' },
  AT_PEER_MEDIAN: { label: 'At peer median on this observable metric', tone: 'stone' },
  BELOW_PEER_MEDIAN: { label: 'Below peer median on this observable metric', tone: 'marigold' },
  NOT_COMPARABLE: { label: 'Not comparable', tone: 'stone' },
}

export const INTERPRETATION: Record<EvidenceInterpretation, StateMeta> = {
  SUPPORTS: { label: 'Supports', description: 'The item supports the metric.', tone: 'sage', icon: CircleCheck },
  DOES_NOT_SUPPORT: { label: 'Does not support', description: 'The item counts against the metric.', tone: 'marigold', icon: CircleMinus },
  EXCLUDED: { label: 'Excluded', description: 'Examined and excluded by an eligibility rule.', tone: 'stone', icon: CircleDashed, dashed: true },
  CONTEXT: { label: 'Context', description: 'Context only (for example third-party enrichment or a vendor claim). Not credited.', tone: 'iris', icon: EyeOff },
}

export const DISPUTE_STATUS: Record<DisputeStatus, { label: string; tone: Tone; description: string }> = {
  OPEN: { label: 'Open', tone: 'plum', description: 'Received; not yet reviewed.' },
  UNDER_REVIEW: { label: 'Under review', tone: 'marigold', description: 'A reviewer is checking the evidence.' },
  CONFIRMED: { label: 'Confirmed', tone: 'stone', description: 'The original finding stands.' },
  CORRECTED: { label: 'Corrected', tone: 'sage', description: 'A later run carries the corrected result.' },
  DISMISSED: { label: 'Dismissed', tone: 'stone', description: 'Closed without change.' },
}

export const VERIFICATION_MODE: Record<VerificationMode, { label: string; tone: Tone; hatch?: boolean; description: string }> = {
  PUBLICLY_MEASURABLE: { label: 'Publicly measurable', tone: 'sage', description: 'Public sources can answer this goal.' },
  PARTIALLY_MEASURABLE: { label: 'Partially measurable', tone: 'marigold', description: 'Public sources give a signal about part of this goal.' },
  NOT_EXTERNALLY_VERIFIABLE: {
    label: 'Not externally verifiable',
    tone: 'iris',
    hatch: true,
    description: 'Public sources cannot meaningfully answer this goal.',
  },
}

/** Tailwind classes per tone. Spelled out in full so Tailwind can scan them. */
export const TONE_CLASSES: Record<Tone, { chip: string; text: string; fill: string; soft: string; dot: string }> = {
  sage: { chip: 'bg-sage/15 text-sage-ink ring-sage/40', text: 'text-sage-ink', fill: 'bg-sage', soft: 'bg-sage/10', dot: 'bg-sage' },
  marigold: {
    chip: 'bg-marigold/20 text-marigold-ink ring-marigold/45',
    text: 'text-marigold-ink',
    fill: 'bg-marigold',
    soft: 'bg-marigold/10',
    dot: 'bg-marigold',
  },
  iris: { chip: 'bg-iris/10 text-iris-ink ring-iris/40', text: 'text-iris-ink', fill: 'bg-iris', soft: 'bg-iris/10', dot: 'bg-iris' },
  vermilion: {
    chip: 'bg-vermilion/10 text-vermilion-ink ring-vermilion/40',
    text: 'text-vermilion-ink',
    fill: 'bg-vermilion',
    soft: 'bg-vermilion/10',
    dot: 'bg-vermilion',
  },
  plum: { chip: 'bg-plum/10 text-plum-ink ring-plum/40', text: 'text-plum-ink', fill: 'bg-plum', soft: 'bg-plum/10', dot: 'bg-plum' },
  stone: { chip: 'bg-paper-2 text-ink-2 ring-line-strong', text: 'text-ink-2', fill: 'bg-ink-3', soft: 'bg-paper-2', dot: 'bg-ink-3' },
}

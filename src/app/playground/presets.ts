import { loadYamlCorpus } from '@/harness/corpus';

export interface Preset {
  id: string;
  label: string;
  family: string;
  expect: string;
  text: string;
  trust: 'user' | 'tool' | 'retrieved';
}

/** Corpus cases offered in the playground dropdown. */
export function presets(): Preset[] {
  try {
    const { cases } = loadYamlCorpus();
    return cases.map((c) => ({
      id: c.id,
      label: `${c.expect === 'block' ? '⚠' : '✓'} ${c.id} — ${c.family}`,
      family: c.family,
      expect: c.expect,
      text: c.payload,
      trust: c.trust ?? (c.delivery === 'indirect-doc' ? 'retrieved' : c.delivery === 'tool-result' ? 'tool' : 'user'),
    }));
  } catch {
    return [];
  }
}

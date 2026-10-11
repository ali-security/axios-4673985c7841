import URLSearchParams from './classes/URLSearchParams.js'
import FormData from './classes/FormData.js'

const hasBrowserEnv = typeof window !== 'undefined' && typeof document !== 'undefined';

const origin = hasBrowserEnv && window.location.href || 'http://localhost';

export default {
  isNode: true,
  classes: {
    URLSearchParams,
    FormData,
    Blob: typeof Blob !== 'undefined' && Blob || null
  },
  protocols: [ 'http', 'https', 'file', 'data' ],
  hasBrowserEnv,
  origin
};

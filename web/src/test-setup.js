import '@testing-library/jest-dom'

Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  }),
})

const getComputedStyle = window.getComputedStyle.bind(window)
window.getComputedStyle = (element, pseudoElement) => {
  if (pseudoElement) {
    return { getPropertyValue: () => '0px' }
  }
  return getComputedStyle(element)
}

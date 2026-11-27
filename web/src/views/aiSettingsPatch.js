// Compare the normalized form values so unit-conversion rounding alone does
// not send a threshold edit. Authority is a single API setting.
export function changedAiSettings(saved, edited) {
  return Object.fromEntries(Object.entries(edited).filter(
    ([key, value]) => JSON.stringify(value) !== JSON.stringify(saved[key]),
  ));
}

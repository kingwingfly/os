// Expectations restrict a launch; authenticated exec metadata supplies the actual scope.
export function validateExpectedSession(value) {
  if (!value || !['session', 'boot'].every(key => typeof value[key] === 'string' && value[key].length > 0 && value[key].length <= 128)) {
    throw Object.assign(new Error('A current login and Machine boot are required.'), { errno: 'EINVAL' });
  }
  return { session: value.session, boot: value.boot };
}
export function checkExpectedSession(expected, image) {
  if (image.login_scope !== expected.session || image.boot !== expected.boot) {
    throw Object.assign(new Error('The login or Machine changed before the application could start.'), { errno: 'ESTALE' });
  }
}

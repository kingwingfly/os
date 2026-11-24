// A failed enqueue has no side effects. Retry only EAGAIN, waking the seat
// between attempts. ESTALE and ENODEV belong to the retired seat/generation.
export async function enqueueSeat(enqueue, wake, retries = 32) {
  for (let attempt = 0; ; attempt++) {
    try { const result = enqueue(); wake(); return result; }
    catch (error) {
      if (error.errno !== 'EAGAIN' || attempt >= retries) throw error;
      wake();
      await new Promise(resolve => setTimeout(resolve, Math.min(32, 2 + attempt * 2)));
    }
  }
}

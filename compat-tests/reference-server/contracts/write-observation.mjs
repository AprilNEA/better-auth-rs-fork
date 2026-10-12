export function writeObservation(serialized) {
  return new Promise((resolve, reject) => {
    process.stdout.write(serialized, error => {
      if (error) reject(error);
      else resolve();
    });
  });
}

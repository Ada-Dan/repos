// Test of function getDatesInRange from BookingApp4\client\src\components\reserve\Reserve.js
const getDatesInRange = (startDate, endDate) => {
  const start = new Date(startDate);
  const end = new Date(endDate);

  const date = new Date(start.getTime());

  const dates = [];

  while (date <= end) {
    dates.push(new Date(date).getTime());
    date.setDate(date.getDate() + 1);
  }

  return dates;
};

// 3 unit tests to ensure date range behaviour is as expected.
// To run this unit test :
//  - Open a terminal in this file's directory "\BookingApp4\unitTesting"
//  - Run npm test to run the test below and see results
test('returns array of dates between start and end date', () => {
    const startDate = '2022-01-01';
    const endDate = '2022-01-05';
    const expectedDates = [
      new Date('2022-01-01').getTime(),
      new Date('2022-01-02').getTime(),
      new Date('2022-01-03').getTime(),
      new Date('2022-01-04').getTime(),
      new Date('2022-01-05').getTime(),
    ];
    const result = getDatesInRange(startDate, endDate);
    expect(result).toEqual(expectedDates);
  });
  
  test('returns empty array when start date is after end date', () => {
    const startDate = '2022-01-05';
    const endDate = '2022-01-01';
    const result = getDatesInRange(startDate, endDate);
    expect(result).toEqual([]);
  });
  
  test('returns array with single date when start and end dates are the same', () => {
    const startDate = '2022-01-01';
    const endDate = '2022-01-01';
    const expectedDates = [new Date('2022-01-01').getTime()];
    const result = getDatesInRange(startDate, endDate);
    expect(result).toEqual(expectedDates);
  });
  
pub fn calculate_mean(numbers: &[f64]) -> f64 {
    let sum: f64 = numbers.iter().sum();
    sum / (numbers.len() as f64)
}

pub fn calculate_median(numbers: &mut [f64]) -> f64 {
    numbers.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = numbers.len() / 2;
    if numbers.len() % 2 == 0 {
        (numbers[mid - 1] + numbers[mid]) / 2.0
    } else {
        numbers[mid]
    }
}

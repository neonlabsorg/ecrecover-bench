//! ecrecover-bench significant module.

/// Formats a float number with precision in the sense of number of significant digits.
pub fn precision(float: f64, prec: usize) -> String {
    // compute absolute value
    let a = float.abs();

    // if abs value is greater than 1, then precision becomes less than "standard"
    let prec = if a >= 1. {
        // reduce by number of digits, minimum 0
        let n = (1. + a.log10().floor()) as usize;
        if n <= prec {
            prec - n
        } else {
            0
        }
        // if precision is less than 1 (but non-zero), then precision becomes greater than "standard"
    } else if a > 0. {
        // increase number of digits
        let n = -(1. + a.log10().floor()) as usize;
        prec + n
        // special case for 0
    } else {
        0
    };

    // format with the given computed precision
    format!("{0:.1$}", float, prec)
}

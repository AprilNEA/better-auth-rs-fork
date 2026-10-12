//! Match the comparison schedule of the pinned JavaScriptCore array sorter.
//!
//! Source: oven-sh/WebKit 2e2aa2290fac856d6f451ceacb58f7f5b44dd057,
//! Source/JavaScriptCore/runtime/StableSort.h. Keep indices until comparisons finish
//! so callbacks retain native record identities and failures cannot publish reordered rows.

#![expect(
    clippy::indexing_slicing,
    reason = "Permutation indices start within the slice; run and gallop bounds stay within their source ranges."
)]

/*
 * Copyright (C) 2024-2026 Apple Inc. All rights reserved.
 * Copyright (C) 2018-2026 the V8 project authors. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010,
 * 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018 Python Software Foundation;
 * All Rights Reserved
 *
 * Part of the implementation, e.g. galloping merge, is coming from Python's TimSort.
 *
 * https://github.com/python/cpython/blob/master/Objects/listobject.c
 *
 * Detailed analysis and a description of the algorithm can be found at:
 *
 * https://github.com/python/cpython/blob/master/Objects/listsort.txt
 */

use std::cmp::Ordering;

use crate::AuthResult;

const RUN_CUTOFF: usize = 8;
const FORCED_RUN: usize = 64;
const MIN_GALLOP: usize = 7;

#[derive(Clone, Copy)]
struct Run {
    begin: usize,
    end: usize,
}

/// Sort with the pinned runtime's fallible comparison schedule and commit only a successful permutation.
pub fn sort_by<T>(
    values: &mut [T],
    compare: impl Fn(&T, &T) -> AuthResult<Ordering>,
) -> AuthResult<()> {
    let mut order = (0..values.len()).collect::<Vec<_>>();
    powersort(&mut order, &|left, right| {
        Ok(compare(&values[left], &values[right])?.is_lt())
    })?;
    for start in 0..order.len() {
        let mut current = start;
        while order[current] != start {
            let next = order[current];
            values.swap(current, next);
            order[current] = current;
            current = next;
        }
        order[current] = current;
    }
    Ok(())
}

type Less<'a> = dyn Fn(usize, usize) -> AuthResult<bool> + 'a;

fn insertion_sort(values: &mut [usize], sorted_header: usize, less: &Less<'_>) -> AuthResult<()> {
    for index in sorted_header + 1..values.len() {
        let mut left = 0;
        let mut right = index;
        while left < right {
            let middle = left + (right - left) / 2;
            if less(values[index], values[middle])? {
                right = middle;
            } else {
                left = middle + 1;
            }
        }
        values[left..=index].rotate_right(1);
    }
    Ok(())
}

fn extend_run(values: &mut [usize], begin: usize, less: &Less<'_>) -> AuthResult<Run> {
    let mut end = begin;
    if end + 1 < values.len() {
        let descending = less(values[end + 1], values[end])?;
        end += 1;
        while end + 1 < values.len() {
            if less(values[end + 1], values[end])? != descending {
                break;
            }
            end += 1;
        }
        if descending {
            values[begin..=end].reverse();
        }
    }
    if end - begin < RUN_CUTOFF {
        let length = FORCED_RUN.min(values.len() - begin);
        insertion_sort(&mut values[begin..begin + length], end - begin, less)?;
        end = begin + length - 1;
    }
    while end + 1 < values.len() {
        if less(values[end + 1], values[end])? {
            break;
        }
        end += 1;
    }
    Ok(Run { begin, end })
}

fn power(left: Run, right: Run, length: usize) -> u32 {
    let first =
        ((left.begin as u128 * 2 + (right.begin - left.begin) as u128) << 62) / length as u128;
    let second =
        ((right.begin as u128 * 2 + (right.end - right.begin + 1) as u128) << 62) / length as u128;
    ((first ^ second) as u64).leading_zeros()
}

fn powersort(values: &mut [usize], less: &Less<'_>) -> AuthResult<()> {
    if values.len() < RUN_CUTOFF {
        return insertion_sort(values, 0, less);
    }
    let mut scratch = vec![0; values.len()];
    let mut stack: Vec<(Run, u32)> = Vec::new();
    let mut min_gallop = MIN_GALLOP;
    let mut first = extend_run(values, 0, less)?;
    while first.end + 1 < values.len() {
        let second = extend_run(values, first.end + 1, less)?;
        let next_power = power(first, second, values.len());
        while let Some((previous, _)) = stack
            .last()
            .copied()
            .filter(|(_, power)| *power > next_power)
        {
            let _ = stack.pop();
            merge_runs(values, &mut scratch, previous, first, less, &mut min_gallop)?;
            first.begin = previous.begin;
        }
        stack.push((first, next_power));
        first = second;
    }
    while let Some((previous, _)) = stack.pop() {
        merge_runs(values, &mut scratch, previous, first, less, &mut min_gallop)?;
        first.begin = previous.begin;
    }
    Ok(())
}

fn gallop_left(key: usize, values: &[usize], hint: usize, less: &Less<'_>) -> AuthResult<usize> {
    let mut last = 0;
    let mut offset = 1;
    let (mut left, mut right) = if less(values[hint], key)? {
        let maximum = values.len() - hint;
        while offset < maximum {
            if !less(values[hint + offset], key)? {
                break;
            }
            last = offset;
            offset = offset.saturating_mul(2).saturating_add(1).min(maximum);
        }
        (hint + last + 1, hint + offset)
    } else {
        let maximum = hint + 1;
        while offset < maximum {
            if less(values[hint - offset], key)? {
                break;
            }
            last = offset;
            offset = offset.saturating_mul(2).saturating_add(1).min(maximum);
        }
        (hint + 1 - offset, hint - last)
    };
    while left < right {
        let middle = left + (right - left) / 2;
        if less(values[middle], key)? {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    Ok(right)
}

fn gallop_right(key: usize, values: &[usize], hint: usize, less: &Less<'_>) -> AuthResult<usize> {
    let mut last = 0;
    let mut offset = 1;
    let (mut left, mut right) = if less(key, values[hint])? {
        let maximum = hint + 1;
        while offset < maximum {
            if !less(key, values[hint - offset])? {
                break;
            }
            last = offset;
            offset = offset.saturating_mul(2).saturating_add(1).min(maximum);
        }
        (hint + 1 - offset, hint - last)
    } else {
        let maximum = values.len() - hint;
        while offset < maximum {
            if less(key, values[hint + offset])? {
                break;
            }
            last = offset;
            offset = offset.saturating_mul(2).saturating_add(1).min(maximum);
        }
        (hint + last + 1, hint + offset)
    };
    while left < right {
        let middle = left + (right - left) / 2;
        if less(key, values[middle])? {
            right = middle;
        } else {
            left = middle + 1;
        }
    }
    Ok(right)
}

fn merge_runs(
    values: &mut [usize],
    scratch: &mut [usize],
    first: Run,
    second: Run,
    less: &Less<'_>,
    min_gallop: &mut usize,
) -> AuthResult<()> {
    merge_into(values, scratch, first, second, less, min_gallop)?;
    values[first.begin..=second.end].copy_from_slice(&scratch[first.begin..=second.end]);
    Ok(())
}

fn merge_into(
    source: &[usize],
    target: &mut [usize],
    first: Run,
    second: Run,
    less: &Less<'_>,
    min_gallop: &mut usize,
) -> AuthResult<()> {
    let mut left = first.begin
        + gallop_right(
            source[second.begin],
            &source[first.begin..=first.end],
            0,
            less,
        )?;
    target[first.begin..left].copy_from_slice(&source[first.begin..left]);
    let left_end = first.end + 1;
    if left == left_end {
        target[second.begin..=second.end].copy_from_slice(&source[second.begin..=second.end]);
        return Ok(());
    }
    let right_end = second.begin
        + gallop_left(
            source[first.end],
            &source[second.begin..=second.end],
            second.end - second.begin,
            less,
        )?;
    target[right_end..=second.end].copy_from_slice(&source[right_end..=second.end]);
    if right_end == second.begin {
        target[left..left_end].copy_from_slice(&source[left..left_end]);
        return Ok(());
    }
    let mut right = second.begin;
    let mut output = left;
    'merge: loop {
        let mut left_wins = 0;
        let mut right_wins = 0;
        while left_wins < *min_gallop && right_wins < *min_gallop {
            if left == left_end || right == right_end {
                break 'merge;
            }
            if less(source[right], source[left])? {
                target[output] = source[right];
                right += 1;
                right_wins += 1;
                left_wins = 0;
            } else {
                target[output] = source[left];
                left += 1;
                left_wins += 1;
                right_wins = 0;
            }
            output += 1;
        }
        *min_gallop += 1;
        loop {
            if *min_gallop > 1 {
                *min_gallop -= 1;
            }
            if left == left_end || right == right_end {
                break 'merge;
            }
            left_wins = gallop_right(source[right], &source[left..left_end], 0, less)?;
            target[output..output + left_wins].copy_from_slice(&source[left..left + left_wins]);
            output += left_wins;
            left += left_wins;
            target[output] = source[right];
            output += 1;
            right += 1;
            if left == left_end || right == right_end {
                break 'merge;
            }
            right_wins = gallop_left(source[left], &source[right..right_end], 0, less)?;
            target[output..output + right_wins].copy_from_slice(&source[right..right + right_wins]);
            output += right_wins;
            right += right_wins;
            target[output] = source[left];
            output += 1;
            left += 1;
            if left == left_end || right == right_end {
                break 'merge;
            }
            if left_wins < MIN_GALLOP && right_wins < MIN_GALLOP {
                break;
            }
        }
        *min_gallop += 1;
    }
    target[output..output + left_end - left].copy_from_slice(&source[left..left_end]);
    output += left_end - left;
    target[output..output + right_end - right].copy_from_slice(&source[right..right_end]);
    Ok(())
}

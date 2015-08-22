//! A tuple for pattern matching purposes, until vector pattern matching is enabled in stable.
//!
//! This code is not very pretty at all but it compiles without enabling any experimental features.

#[derive(Debug)]
pub enum Tup<A,B,C,D,E,F,G,H,I> {
    T0,
    T1(A),
    T2(A, B),
    T3(A, B, C),
    T4(A, B, C, D),
    T5(A, B, C, D, E),
    T6(A, B, C, D, E, F),
    T7(A, B, C, D, E, F, G),
    T8(A, B, C, D, E, F, G, H),
    T9(A, B, C, D, E, F, G, H, I),
}

pub type TupT<T> = Tup<T,T,T,T,T,T,T,T,T>;

pub fn vec_to_tup<T: Clone>(vec: &Vec<T>) -> Option<Tup<T,T,T,T,T,T,T,T,T>> {
    match vec.len() {
        0 => Some(Tup::T0),
        1 => Some(Tup::T1(vec[0].clone())),
        2 => Some(Tup::T2(vec[0].clone(), vec[1].clone())),
        3 => Some(Tup::T3(vec[0].clone(), vec[1].clone(), vec[2].clone())),
        4 => Some(Tup::T4(vec[0].clone(), vec[1].clone(), vec[2].clone(), vec[3].clone())),
        5 => Some(Tup::T5(vec[0].clone(), vec[1].clone(), vec[2].clone(), vec[3].clone(), vec[4].clone())),
        6 => Some(Tup::T6(vec[0].clone(), vec[1].clone(), vec[2].clone(), vec[3].clone(), vec[4].clone(), vec[5].clone())),
        7 => Some(Tup::T7(vec[0].clone(), vec[1].clone(), vec[2].clone(), vec[3].clone(), vec[4].clone(), vec[5].clone(), vec[6].clone())),
        8 => Some(Tup::T8(vec[0].clone(), vec[1].clone(), vec[2].clone(), vec[3].clone(), vec[4].clone(), vec[5].clone(), vec[6].clone(), vec[7].clone())),
        9 => Some(Tup::T9(vec[0].clone(), vec[1].clone(), vec[2].clone(), vec[3].clone(), vec[4].clone(), vec[5].clone(), vec[6].clone(), vec[7].clone(), vec[8].clone())),
        _ => None,
    }
}

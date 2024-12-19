package slices

// Map returns a new slice containing the results of applying the given function
func Map[S ~[]T, T any, O any](s S, f func(T) O) []O {
	out := make([]O, len(s))
	for i := range s {
		out[i] = f(s[i])
	}
	return out
}

package sets

type Set[T comparable] struct {
	elements map[T]struct{}
}

func NewSet[T comparable](elements ...T) *Set[T] {
	s := &Set[T]{elements: make(map[T]struct{})}
	s.Add(elements...)
	return s
}

func (s *Set[T]) Add(elements ...T) {
	for _, element := range elements {
		s.elements[element] = struct{}{}
	}
}

func (s *Set[T]) Remove(elements ...T) {
	for _, element := range elements {
		delete(s.elements, element)
	}
}

func (s *Set[T]) Contains(element T) bool {
	_, exists := s.elements[element]
	return exists
}

func (s *Set[T]) Size() int {
	return len(s.elements)
}

func (s *Set[T]) Clear() {
	s.elements = make(map[T]struct{})
}

func (s *Set[T]) Union(other *Set[T]) {
	for elem := range other.elements {
		s.Add(elem)
	}
}

func (s *Set[T]) Intersection(other *Set[T]) {
	for elem := range s.elements {
		if !other.Contains(elem) {
			s.Remove(elem)
		}
	}
}

func (s *Set[T]) Difference(other *Set[T]) {
	for elem := range other.elements {
		if s.Contains(elem) {
			s.Remove(elem)
		}
	}
}

func (s *Set[T]) List() []T {
	elementsList := make([]T, 0, len(s.elements))
	for elem := range s.elements {
		elementsList = append(elementsList, elem)
	}
	return elementsList
}

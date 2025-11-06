from abc import ABC, abstractmethod
from typing import Any, Generic, Optional, TypeVar

T = TypeVar("T")


class BaseRepository(ABC, Generic[T]):
    @abstractmethod
    def get_by_id(self, entity_id: Any) -> Optional[T]:
        """Obtiene una entidad por su ID."""
        pass

    @abstractmethod
    def upsert(self, entity: T) -> T:
        """Inserta o actualiza una entidad."""
        pass

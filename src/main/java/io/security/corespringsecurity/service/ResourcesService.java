package io.security.corespringsecurity.service;

import java.util.List;

import io.security.corespringsecurity.domain.entity.Resources;

public interface ResourcesService {

    Resources getResources(long id);

    List<Resources> getResources();

    void createResources(Resources Resources);

    void deleteResources(long id);
}
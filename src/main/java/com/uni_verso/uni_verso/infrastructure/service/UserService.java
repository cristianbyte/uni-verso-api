package com.uni_verso.uni_verso.infrastructure.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.uni_verso.uni_verso.api.dto.request.UserRequest;
import com.uni_verso.uni_verso.api.dto.response.PairingResponse;
import com.uni_verso.uni_verso.api.dto.response.UserResponse;
import com.uni_verso.uni_verso.api.error.IdNotFoundException;
import com.uni_verso.uni_verso.api.error.InvalidOperationException;
import com.uni_verso.uni_verso.domain.entity.Pairing;
import com.uni_verso.uni_verso.domain.entity.User;
import com.uni_verso.uni_verso.domain.repo.PairingRepo;
import com.uni_verso.uni_verso.domain.repo.UserRepo;
import com.uni_verso.uni_verso.infrastructure.abstract_service.IUserService;
import com.uni_verso.uni_verso.infrastructure.mapper.PairingMapper;
import com.uni_verso.uni_verso.infrastructure.mapper.UserMapper;

import lombok.AllArgsConstructor;

@Service
@Transactional
@AllArgsConstructor
public class UserService implements IUserService {

    private final UserRepo userRepository;

    private final PairingRepo pairingRepository;

    private final UserMapper userMapper;

    private final PairingMapper pairingMapper;

    @Override
    public UserResponse create(UserRequest request) {
        // Pending: Verify the user via email.
        if(userRepository.findById(request.getId()).isPresent()){
            throw new InvalidOperationException("User already exists with id: " + request.getId());
        }

        User user = userMapper.toEntity(request);
        return userMapper.toResponse(userRepository.save(user));
    }

    @Override
    public UserResponse getById(String id) {
        User user = this.find(id);

        UserResponse response = userMapper.toResponse(user);
        
        List<Pairing> pairings = pairingRepository.findByCreatorUserIdOrPairedUserId(id, id);
        
        List<PairingResponse> pairingResponses = pairings.stream()
            .map(pairingMapper::toResponse)
            .collect(Collectors.toList());
        
        response.setPairings(pairingResponses);
        
        return response;
    }

    @Override
    public UserResponse update(String id, UserRequest request) {
        User user = find(id);
        userMapper.toUpdate(request, user);
        return userMapper.toResponse(userRepository.save(user));
    }

    @Override
    public void delete(String id) {
        userRepository.delete(this.find(id));
    }


    public User find(String id) {
        return userRepository.findById(id).orElseThrow(() -> new IdNotFoundException("User not found with id: " + id));
    }
}

# CS 118 Winter 25 Project 2

This repository contains starter code for [CS 118's Winter 25 Project
1](https://cs118.org/projects/project2).

For more information on how to use the local autograder, visit [the course
website](https://cs118.org/misc/autograder). For more information on the `libsecurity`
`libtransport` libraries, also visit [the course website](https://cs118.org/projects).

# Project Overview

## Design Choices

Our implementation follows a modular design to ensure clarity and maintainability. We structured the code into separate components for packet handling, connection management, and retransmission logic. The sliding window protocol was implemented to efficiently manage packet flow and optimize throughput. We also utilized selective acknowledgments to handle lost packets efficiently, reducing unnecessary retransmissions.

## Challenges Encountered

One of the main challenges was handling out-of-order packets and ensuring reliable data transfer. Additionally, tuning the retransmission timeout (RTO) to balance between performance and reliability proved difficult. Another issue arose in managing buffer sizes effectively to prevent excessive memory usage while ensuring smooth data flow.

## Solutions Implemented

To address out-of-order packets, we implemented a buffer that stores received packets until they can be processed in order. The RTO was dynamically adjusted based on estimated round-trip times to optimize retransmission behavior. Lastly, buffer management strategies were employed to dynamically allocate memory as needed, preventing excessive usage while maintaining performance.
